rule TTP_XOR_WriteProcessMemory_289f {
  strings:
    $key_289f = { 7f ed [2] 4d cf [2] 4b fa [2] 65 fa [2] 5a e6 }

  condition:
    any of them
}