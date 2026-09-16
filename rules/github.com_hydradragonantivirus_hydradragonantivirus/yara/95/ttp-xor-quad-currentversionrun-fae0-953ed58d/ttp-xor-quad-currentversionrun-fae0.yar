rule TTP_XOR_QUAD_CurrentVersionRun_fae0 {
  strings:
    $key_fae0 = { a9 8f [2] 8d 81 [2] a6 ad [2] 88 8f [2] 9c 94 [2] 93 8e [2] 8d 93 [2] 8f 92 [2] 94 94 [2] 88 93 [2] 94 bc }

  condition:
    any of them
}