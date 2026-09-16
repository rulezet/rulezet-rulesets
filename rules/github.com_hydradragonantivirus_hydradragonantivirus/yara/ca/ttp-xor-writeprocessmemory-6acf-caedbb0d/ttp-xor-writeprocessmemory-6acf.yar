rule TTP_XOR_WriteProcessMemory_6acf {
  strings:
    $key_6acf = { 3d bd [2] 0f 9f [2] 09 aa [2] 27 aa [2] 18 b6 }

  condition:
    any of them
}