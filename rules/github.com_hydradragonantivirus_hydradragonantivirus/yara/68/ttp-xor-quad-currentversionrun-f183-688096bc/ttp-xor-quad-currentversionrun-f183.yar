rule TTP_XOR_QUAD_CurrentVersionRun_f183 {
  strings:
    $key_f183 = { a2 ec [2] 86 e2 [2] ad ce [2] 83 ec [2] 97 f7 [2] 98 ed [2] 86 f0 [2] 84 f1 [2] 9f f7 [2] 83 f0 [2] 9f df }

  condition:
    any of them
}