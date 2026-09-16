import "pe"
rule Password_Protector__c__MiniSoft_1992 {
  strings:
    $a0 = { 06 0E 0E 07 1F E8 00 00 5B 83 EB 08 BA 27 01 03 D3 E8 3C 02 BA EA }

  condition:
    $a0 at pe.entry_point
}