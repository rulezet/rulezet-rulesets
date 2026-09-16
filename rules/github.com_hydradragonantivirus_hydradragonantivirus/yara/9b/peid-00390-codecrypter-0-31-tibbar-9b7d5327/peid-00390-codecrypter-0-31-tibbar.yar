import "pe"
rule PEiD_00390_codeCrypter_0_31____Tibbar_ {
  meta:
    description = "[codeCrypter 0.31 -> Tibbar]"
    ep_only     = "true"

  strings:
    $a = { 50 58 53 5B 90 BB ?? ?? ?? 00 FF E3 90 CC CC CC 55 8B EC 5D C3 CC CC CC CC CC CC CC CC CC CC CC }

  condition:
    $a at pe.entry_point
}