rule TTP_XOR_QUAD_CurrentVersionRun_eee3 {
  strings:
    $key_eee3 = { bd 8c [2] 99 82 [2] b2 ae [2] 9c 8c [2] 88 97 [2] 87 8d [2] 99 90 [2] 9b 91 [2] 80 97 [2] 9c 90 [2] 80 bf }

  condition:
    any of them
}