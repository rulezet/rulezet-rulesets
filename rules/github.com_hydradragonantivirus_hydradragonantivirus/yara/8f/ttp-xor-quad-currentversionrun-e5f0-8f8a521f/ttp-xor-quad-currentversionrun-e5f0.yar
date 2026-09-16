rule TTP_XOR_QUAD_CurrentVersionRun_e5f0 {
  strings:
    $key_e5f0 = { b6 9f [2] 92 91 [2] b9 bd [2] 97 9f [2] 83 84 [2] 8c 9e [2] 92 83 [2] 90 82 [2] 8b 84 [2] 97 83 [2] 8b ac }

  condition:
    any of them
}