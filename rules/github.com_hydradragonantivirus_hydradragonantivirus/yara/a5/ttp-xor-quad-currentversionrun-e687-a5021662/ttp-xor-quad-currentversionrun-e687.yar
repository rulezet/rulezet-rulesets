rule TTP_XOR_QUAD_CurrentVersionRun_e687 {
  strings:
    $key_e687 = { b5 e8 [2] 91 e6 [2] ba ca [2] 94 e8 [2] 80 f3 [2] 8f e9 [2] 91 f4 [2] 93 f5 [2] 88 f3 [2] 94 f4 [2] 88 db }

  condition:
    any of them
}