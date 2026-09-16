rule TTP_XOR_WriteProcessMemory_e94c {
  strings:
    $key_e94c = { be 3e [2] 8c 1c [2] 8a 29 [2] a4 29 [2] 9b 35 }

  condition:
    any of them
}