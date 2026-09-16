import "pe"
rule PEEncrypt_v4_0b__JunkCode_ {
  strings:
    $a0 = { 66 ?? ?? 00 66 83 ?? 00 }

  condition:
    $a0 at pe.entry_point
}