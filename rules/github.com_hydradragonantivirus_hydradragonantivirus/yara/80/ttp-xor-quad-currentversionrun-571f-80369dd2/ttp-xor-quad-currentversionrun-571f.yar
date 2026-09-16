rule TTP_XOR_QUAD_CurrentVersionRun_571f {
  strings:
    $key_571f = { 04 70 [2] 20 7e [2] 0b 52 [2] 25 70 [2] 31 6b [2] 3e 71 [2] 20 6c [2] 22 6d [2] 39 6b [2] 25 6c [2] 39 43 }

  condition:
    any of them
}