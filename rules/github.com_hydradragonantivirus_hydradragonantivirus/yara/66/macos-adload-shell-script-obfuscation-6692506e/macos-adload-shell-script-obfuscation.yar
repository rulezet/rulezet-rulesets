rule macos_adload_shell_script_obfuscation {
  meta:
    description = "MACOS.ADLOAD"

  strings:
    $shebang = "#!/bin/bash"

    $defs = /([A-Z]{1}\=\"[a-z]{1}\"\;){5,}/

    $subs = /(\$\{[A-Z]{1}\}){5,}/

  condition:
    $shebang at 0 and filesize < 100KB and all of them

}