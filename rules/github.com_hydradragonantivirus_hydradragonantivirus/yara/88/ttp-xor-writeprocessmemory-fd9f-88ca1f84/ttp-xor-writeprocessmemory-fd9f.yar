rule TTP_XOR_WriteProcessMemory_fd9f {
  strings:
    $key_fd9f = { aa ed [2] 98 cf [2] 9e fa [2] b0 fa [2] 8f e6 }

  condition:
    any of them
}