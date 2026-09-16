rule TTP_XOR_WriteProcessMemory_44eb {
  strings:
    $key_44eb = { 13 99 [2] 21 bb [2] 27 8e [2] 09 8e [2] 36 92 }

  condition:
    any of them
}