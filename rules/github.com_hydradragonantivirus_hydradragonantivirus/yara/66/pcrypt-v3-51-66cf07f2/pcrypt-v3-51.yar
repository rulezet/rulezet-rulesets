import "pe"
rule PCrypt_v3_51 {
  strings:
    $a0 = { 50 43 52 59 50 54 FF 76 33 2E 35 31 00 E9 }

  condition:
    $a0 at pe.entry_point
}