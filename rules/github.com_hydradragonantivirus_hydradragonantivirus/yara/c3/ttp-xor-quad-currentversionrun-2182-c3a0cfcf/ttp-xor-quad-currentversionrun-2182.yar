rule TTP_XOR_QUAD_CurrentVersionRun_2182 {
  strings:
    $key_2182 = { 72 ed [2] 56 e3 [2] 7d cf [2] 53 ed [2] 47 f6 [2] 48 ec [2] 56 f1 [2] 54 f0 [2] 4f f6 [2] 53 f1 [2] 4f de }

  condition:
    any of them
}