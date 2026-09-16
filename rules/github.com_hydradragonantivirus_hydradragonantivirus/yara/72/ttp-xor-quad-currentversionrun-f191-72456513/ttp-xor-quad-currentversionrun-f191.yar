rule TTP_XOR_QUAD_CurrentVersionRun_f191 {
  strings:
    $key_f191 = { a2 fe [2] 86 f0 [2] ad dc [2] 83 fe [2] 97 e5 [2] 98 ff [2] 86 e2 [2] 84 e3 [2] 9f e5 [2] 83 e2 [2] 9f cd }

  condition:
    any of them
}