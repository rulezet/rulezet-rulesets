rule TTP_XOR_QUAD_CurrentVersionRun_0182 {
  strings:
    $key_0182 = { 52 ed [2] 76 e3 [2] 5d cf [2] 73 ed [2] 67 f6 [2] 68 ec [2] 76 f1 [2] 74 f0 [2] 6f f6 [2] 73 f1 [2] 6f de }

  condition:
    any of them
}