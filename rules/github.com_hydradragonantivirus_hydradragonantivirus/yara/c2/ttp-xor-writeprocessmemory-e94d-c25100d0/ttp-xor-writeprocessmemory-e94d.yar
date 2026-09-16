rule TTP_XOR_WriteProcessMemory_e94d {
  strings:
    $key_e94d = { be 3f [2] 8c 1d [2] 8a 28 [2] a4 28 [2] 9b 34 }

  condition:
    any of them
}