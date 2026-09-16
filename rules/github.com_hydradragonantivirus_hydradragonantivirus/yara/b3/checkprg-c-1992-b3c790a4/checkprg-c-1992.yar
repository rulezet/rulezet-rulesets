import "pe"
rule CHECKPRG__c__1992 {
  strings:
    $a0 = { 33 C0 BE ?? ?? 8B D8 B9 ?? ?? BF ?? ?? BA ?? ?? 47 4A 74 }

  condition:
    $a0 at pe.entry_point
}