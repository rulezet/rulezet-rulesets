rule TTP_XOR_WriteProcessMemory_e94f {
  strings:
    $key_e94f = { be 3d [2] 8c 1f [2] 8a 2a [2] a4 2a [2] 9b 36 }

  condition:
    any of them
}