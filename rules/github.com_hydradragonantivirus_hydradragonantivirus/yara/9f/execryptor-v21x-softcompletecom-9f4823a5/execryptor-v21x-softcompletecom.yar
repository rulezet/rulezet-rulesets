import "pe"
rule _EXECryptor_V21X__SoftCompletecom_ {
  meta:
    description = "EXECryptor V2.1X -> SoftComplete.com"

  strings:
    $0 = { E9 ?? ?? ?? ?? 66 9C 60 50 8D 88 ?? ?? ?? ?? 8D 90 04 16 ?? ?? 8B DC 8B E1 }

  condition:
    $0 at pe.entry_point
}