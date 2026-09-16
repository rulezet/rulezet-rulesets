import "pe"
rule CrackStop_v1_01__c__Stefan_Esser_1997 {
  strings:
    $a0 = { B4 48 BB FF FF B9 EB 27 8B EC CD 21 FA FC }

  condition:
    $a0 at pe.entry_point
}