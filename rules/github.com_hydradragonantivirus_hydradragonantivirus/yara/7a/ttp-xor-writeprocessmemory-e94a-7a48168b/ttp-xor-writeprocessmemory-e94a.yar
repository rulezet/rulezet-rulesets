rule TTP_XOR_WriteProcessMemory_e94a {
  strings:
    $key_e94a = { be 38 [2] 8c 1a [2] 8a 2f [2] a4 2f [2] 9b 33 }

  condition:
    any of them
}