rule TTP_XOR_QUAD_CurrentVersionRun_f151 {
  strings:
    $key_f151 = { a2 3e [2] 86 30 [2] ad 1c [2] 83 3e [2] 97 25 [2] 98 3f [2] 86 22 [2] 84 23 [2] 9f 25 [2] 83 22 [2] 9f 0d }

  condition:
    any of them
}