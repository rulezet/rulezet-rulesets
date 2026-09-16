import "pe"
rule Werus_Crypter_1_0___by_Kas {
  strings:
    $a0 = { BB E8 12 40 00 80 33 05 E9 7D FF FF FF }

  condition:
    $a0 at pe.entry_point
}