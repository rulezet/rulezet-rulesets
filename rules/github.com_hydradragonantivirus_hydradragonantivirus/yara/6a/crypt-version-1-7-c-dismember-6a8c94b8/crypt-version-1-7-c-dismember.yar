import "pe"
rule CRYPT_Version_1_7__c__Dismember {
  strings:
    $a0 = { 0E 17 9C 58 F6 ?? ?? 74 ?? E9 }

  condition:
    $a0 at pe.entry_point
}