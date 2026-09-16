rule TTP_XOR_QUAD_CurrentVersionRun_f7e0 {
  strings:
    $key_f7e0 = { a4 8f [2] 80 81 [2] ab ad [2] 85 8f [2] 91 94 [2] 9e 8e [2] 80 93 [2] 82 92 [2] 99 94 [2] 85 93 [2] 99 bc }

  condition:
    any of them
}