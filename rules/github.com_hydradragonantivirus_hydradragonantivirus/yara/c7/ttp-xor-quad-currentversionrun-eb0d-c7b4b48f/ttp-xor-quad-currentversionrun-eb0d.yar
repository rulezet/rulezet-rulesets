rule TTP_XOR_QUAD_CurrentVersionRun_eb0d {
  strings:
    $key_eb0d = { b8 62 [2] 9c 6c [2] b7 40 [2] 99 62 [2] 8d 79 [2] 82 63 [2] 9c 7e [2] 9e 7f [2] 85 79 [2] 99 7e [2] 85 51 }

  condition:
    any of them
}