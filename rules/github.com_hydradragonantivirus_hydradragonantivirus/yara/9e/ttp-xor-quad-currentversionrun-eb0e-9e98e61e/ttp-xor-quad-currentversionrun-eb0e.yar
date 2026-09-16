rule TTP_XOR_QUAD_CurrentVersionRun_eb0e {
  strings:
    $key_eb0e = { b8 61 [2] 9c 6f [2] b7 43 [2] 99 61 [2] 8d 7a [2] 82 60 [2] 9c 7d [2] 9e 7c [2] 85 7a [2] 99 7d [2] 85 52 }

  condition:
    any of them
}