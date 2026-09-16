rule TTP_XOR_QUAD_CurrentVersionRun_eb1f {
  strings:
    $key_eb1f = { b8 70 [2] 9c 7e [2] b7 52 [2] 99 70 [2] 8d 6b [2] 82 71 [2] 9c 6c [2] 9e 6d [2] 85 6b [2] 99 6c [2] 85 43 }

  condition:
    any of them
}