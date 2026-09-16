import "pe"
rule PEncrypt_v3_1 {
  strings:
    $a0 = { E9 ?? ?? ?? 00 F0 0F C6 }

  condition:
    $a0 at pe.entry_point
}