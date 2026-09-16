rule TTP_XOR_WriteProcessMemory_496b {
  strings:
    $key_496b = { 1e 19 [2] 2c 3b [2] 2a 0e [2] 04 0e [2] 3b 12 }

  condition:
    any of them
}