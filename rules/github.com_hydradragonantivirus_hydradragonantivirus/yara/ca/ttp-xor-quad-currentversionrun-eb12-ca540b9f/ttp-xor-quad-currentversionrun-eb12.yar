rule TTP_XOR_QUAD_CurrentVersionRun_eb12 {
  strings:
    $key_eb12 = { b8 7d [2] 9c 73 [2] b7 5f [2] 99 7d [2] 8d 66 [2] 82 7c [2] 9c 61 [2] 9e 60 [2] 85 66 [2] 99 61 [2] 85 4e }

  condition:
    any of them
}