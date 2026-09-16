rule TTP_XOR_QUAD_CurrentVersionRun_d982 {
  strings:
    $key_d982 = { 8a ed [2] ae e3 [2] 85 cf [2] ab ed [2] bf f6 [2] b0 ec [2] ae f1 [2] ac f0 [2] b7 f6 [2] ab f1 [2] b7 de }

  condition:
    any of them
}