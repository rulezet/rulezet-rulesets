rule TTP_XOR_QUAD_CurrentVersionRun_1182 {
  strings:
    $key_1182 = { 42 ed [2] 66 e3 [2] 4d cf [2] 63 ed [2] 77 f6 [2] 78 ec [2] 66 f1 [2] 64 f0 [2] 7f f6 [2] 63 f1 [2] 7f de }

  condition:
    any of them
}