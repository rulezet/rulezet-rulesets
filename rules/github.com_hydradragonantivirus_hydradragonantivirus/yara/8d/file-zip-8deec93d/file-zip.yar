rule file_zip {
  meta:
    description   = "Finds files that look like ZIP archives"
    last_modified = "2024-02-12"
    author        = "@petermstewart"
    DaysofYara    = "43/100"
    ref           = "https://en.wikipedia.org/wiki/ZIP_(file_format)"

  strings:
    $local_file_header        = { 50 4b 03 04 }
    $central_directory_header = { 50 4b 01 02 }
    $end_of_central_directory = { 50 4b 05 06 }

  condition:
    $local_file_header at 0 and
    $central_directory_header and
    $end_of_central_directory
}