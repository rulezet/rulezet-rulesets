rule TTP_XOR_QUAD_CurrentVersionRun_aa98 {
  strings:
    $key_aa98 = { f9 f7 [2] dd f9 [2] f6 d5 [2] d8 f7 [2] cc ec [2] c3 f6 [2] dd eb [2] df ea [2] c4 ec [2] d8 eb [2] c4 c4 }

  condition:
    any of them
}