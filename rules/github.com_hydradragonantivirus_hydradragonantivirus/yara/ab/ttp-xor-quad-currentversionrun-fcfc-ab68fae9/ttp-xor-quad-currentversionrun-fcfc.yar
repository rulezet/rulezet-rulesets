rule TTP_XOR_QUAD_CurrentVersionRun_fcfc {
  strings:
    $key_fcfc = { af 93 [2] 8b 9d [2] a0 b1 [2] 8e 93 [2] 9a 88 [2] 95 92 [2] 8b 8f [2] 89 8e [2] 92 88 [2] 8e 8f [2] 92 a0 }

  condition:
    any of them
}