import "pe"
rule PMODE_W_v_1_12__1_16__1_21__1_33_DOS_extender {
  strings:
    $a0 = { FC 16 07 BF ?? ?? 8B F7 57 B9 ?? ?? F3 A5 06 1E 07 1F 5F BE ?? ?? 06 0E A4 }

  condition:
    $a0 at pe.entry_point
}