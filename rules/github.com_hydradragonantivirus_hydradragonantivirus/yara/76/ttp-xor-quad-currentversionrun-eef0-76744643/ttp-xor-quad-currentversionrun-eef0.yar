rule TTP_XOR_QUAD_CurrentVersionRun_eef0 {
  strings:
    $key_eef0 = { bd 9f [2] 99 91 [2] b2 bd [2] 9c 9f [2] 88 84 [2] 87 9e [2] 99 83 [2] 9b 82 [2] 80 84 [2] 9c 83 [2] 80 ac }

  condition:
    any of them
}