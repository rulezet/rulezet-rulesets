rule TTP_XOR_WriteProcessMemory_496a {
  strings:
    $key_496a = { 1e 18 [2] 2c 3a [2] 2a 0f [2] 04 0f [2] 3b 13 }

  condition:
    any of them
}