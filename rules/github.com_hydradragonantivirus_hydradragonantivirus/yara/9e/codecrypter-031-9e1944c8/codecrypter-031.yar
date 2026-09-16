rule _codeCrypter_031_ {
  meta:
    description = "codeCrypter 0.31"

  strings:
    $0 = { 50 58 53 5B 90 BB ?? ?? 40 00 FF E3 90 CC CC CC 55 8B EC 5D C3 CC CC CC CC CC CC CC CC CC CC CC }

  condition:
    $0
}