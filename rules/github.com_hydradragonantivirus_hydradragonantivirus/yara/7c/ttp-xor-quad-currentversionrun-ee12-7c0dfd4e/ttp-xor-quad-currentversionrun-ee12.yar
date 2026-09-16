rule TTP_XOR_QUAD_CurrentVersionRun_ee12 {
  strings:
    $key_ee12 = { bd 7d [2] 99 73 [2] b2 5f [2] 9c 7d [2] 88 66 [2] 87 7c [2] 99 61 [2] 9b 60 [2] 80 66 [2] 9c 61 [2] 80 4e }

  condition:
    any of them
}