rule TTP_XOR_QUAD_CurrentVersionRun_eef2 {
  strings:
    $key_eef2 = { bd 9d [2] 99 93 [2] b2 bf [2] 9c 9d [2] 88 86 [2] 87 9c [2] 99 81 [2] 9b 80 [2] 80 86 [2] 9c 81 [2] 80 ae }

  condition:
    any of them
}