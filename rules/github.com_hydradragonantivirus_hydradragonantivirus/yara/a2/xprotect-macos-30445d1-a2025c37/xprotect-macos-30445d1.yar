rule XProtect_MACOS_30445d1 {
  meta:
    description = "MACOS.30445d1"

  strings:
    $a1 = "#!/bin/sh"
    $a2 = "#!/bin/bash"
    $b  = "hint=\"$(ls | grep -v '1.png\\|2.icns\\|converter.tool\\|script-enc')\""
    $c  = "cmd=\"$(openssl enc -d -aes-256-cbc -A -base64 -k $hint -in script-enc | sh -)\""

  condition:
    any of ($a*) and $b and $c and filesize < 5MB
}