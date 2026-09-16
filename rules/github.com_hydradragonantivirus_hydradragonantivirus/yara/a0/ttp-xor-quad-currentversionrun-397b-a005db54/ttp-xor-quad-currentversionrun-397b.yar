rule TTP_XOR_QUAD_CurrentVersionRun_397b {
  strings:
    $key_397b = { 6a 14 [2] 4e 1a [2] 65 36 [2] 4b 14 [2] 5f 0f [2] 50 15 [2] 4e 08 [2] 4c 09 [2] 57 0f [2] 4b 08 [2] 57 27 }

  condition:
    any of them
}