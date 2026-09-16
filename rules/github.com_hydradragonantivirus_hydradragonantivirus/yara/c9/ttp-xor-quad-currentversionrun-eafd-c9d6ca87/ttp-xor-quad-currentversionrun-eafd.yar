rule TTP_XOR_QUAD_CurrentVersionRun_eafd {
  strings:
    $key_eafd = { b9 92 [2] 9d 9c [2] b6 b0 [2] 98 92 [2] 8c 89 [2] 83 93 [2] 9d 8e [2] 9f 8f [2] 84 89 [2] 98 8e [2] 84 a1 }

  condition:
    any of them
}