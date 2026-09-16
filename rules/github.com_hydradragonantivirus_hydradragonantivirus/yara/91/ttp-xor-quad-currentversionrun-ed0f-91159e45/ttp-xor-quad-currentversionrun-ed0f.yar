rule TTP_XOR_QUAD_CurrentVersionRun_ed0f {
  strings:
    $key_ed0f = { be 60 [2] 9a 6e [2] b1 42 [2] 9f 60 [2] 8b 7b [2] 84 61 [2] 9a 7c [2] 98 7d [2] 83 7b [2] 9f 7c [2] 83 53 }

  condition:
    any of them
}