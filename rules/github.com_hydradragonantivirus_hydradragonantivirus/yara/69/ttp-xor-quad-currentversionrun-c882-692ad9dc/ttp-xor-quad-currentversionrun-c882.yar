rule TTP_XOR_QUAD_CurrentVersionRun_c882 {
  strings:
    $key_c882 = { 9b ed [2] bf e3 [2] 94 cf [2] ba ed [2] ae f6 [2] a1 ec [2] bf f1 [2] bd f0 [2] a6 f6 [2] ba f1 [2] a6 de }

  condition:
    any of them
}