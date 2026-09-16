import "pe"
rule EXECryptor_2_2_4____Strongbit_SoftComplete_Development__h1_ {
  strings:
    $a0 = { E8 F7 FE FF FF 05 ?? ?? 00 00 FF E0 E8 EB FE FF FF 05 ?? ?? 00 00 FF E0 E8 04 00 00 00 FF FF FF FF 5E C3 }

  condition:
    $a0 at pe.entry_point
}