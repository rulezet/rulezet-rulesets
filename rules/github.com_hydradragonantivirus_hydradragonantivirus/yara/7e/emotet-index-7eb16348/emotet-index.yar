rule emotet_index {
  meta:
    description = "PHP - file emotet_index.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-10-11"
    hash1       = "3e23c28ef4b2286f513b8c32f8948e0a6770511d89d2cfd44c1532905b3a0e7f"

  strings:
    $x1  = "private $contentData = '7P1/fFTF1TiO3/2RcEkWdsEgUYNEiUobtNGgJS5oErIhWpZuEpKAGqAt8KSpVQp7ASsLiTfb5uayFZ9KH9vSFqq2tPo80kohWoq7JOYH" ascii
    $s2  = "} public function execute() { $sp53dcff = '.' . sha1(basename(dirname(__FILE__)))" fullword ascii
    $s3  = "$sp46a5c8 = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';" fullword ascii
    $s4  = "private $contentName = '7ve0veit.exe';" fullword ascii
    $s5  = "header('Content-Transfer-Encoding: binary')" fullword ascii
    $s6  = "echo $sp0b39f9->execute();" fullword ascii
    $s7  = "8CiSeGAuxtyJMQLl0eYeXLq/mjbDDzVVC5Eb9kNGcHdlLeyTazTkwqh2Gz7AzHdIeE5U7EMtk6i0YFlDAxuquMhqPrwGEQbKqDPhdROuzmrjEwbOrF543QWdvOCkYFpR" ascii
    $s8  = "header('Content-Type: ' . $this->contentType)" fullword ascii
    $s9  = "header('Content-Disposition: attachment" fullword ascii
    $s10 = "if ($spe314ae > 0) { $sp6316ba = json_decode(fread($sp7d2336, $spe314ae), true)" fullword ascii
    $s11 = "return gzinflate(base64_decode($this->contentData))" fullword ascii
    $s12 = "if (($sp7d2336 = fopen($sp53dcff, 'c+')) !== false) { if (flock($sp7d2336, LOCK_EX)) { $sp6316ba = array()" fullword ascii
    $s13 = "} setcookie(uniqid(), time(), time() + 60, '/')" fullword ascii
    $s14 = "irq0gCMdw+obIIjGnCFe7cb1rYYKjPfHW0067jzJ8Q+Fnd6Ewb+RakJ6nMEQ6JFW0fLmf4SEtpEqZpe9aikjWwBxIDqfq9aNIkg97ZWHXCogWHQeTqoPelflrunSrfdH" ascii
    $s15 = "xZZNN7hYCl8XYf3vj+diHT81WAtV4caZxkYZjc8vTjXpaz7Eye0zdbWfs4hdmUmaf4SduXyc5u8exJ2Qsq8LF9p7ycML/ke1e8YHF6ndk0ieD38z4IrChATK1u8mkfpH" ascii
    $s16 = "/5Fx0wY3BKfI9oljUFhd0e/Nsur1GTVavjKOqtsGmo2to/YV22d1f8Z6sZkNtlDmatdu9aOmD4Zu4l58RHvT7YjdXr6By+1S9wr1THN//YSzbzS9iyloGM2ZH1Jm2Qr1" ascii
    $s17 = "7VtrUJxcJxJVSrHzbZ8J//KeLGETv87kGjLBitaUMv4vcxoC+/YJQvAuvh6R5l7HrFHWZ2Q4FMI3lP9ixGGavVqbeHz+eWm0tI08r2wVl7QtEiHM07J1fXOzljAzi+kt" ascii
    $s18 = "INgPAmTD2XzJRnG3wCQeCRc3nF2LE/PXvQsazj7ozW84u9V7U8PZFdLl4RvOu34XvlY+V+edKZ+7H8vY4hXPuw6Gp0JB512/Daeed//mvPu3Db6DwE3JeZCvVYFG8P1O" ascii
    $s19 = "06Z9imJ8f3Bn//TT5rfeyeA5Er10Pn/6M/5zLHjB5/AM96L/l06a+AnfS4dt+5z57H7ieem5rZ99X/+nRl+wOD5L5V85g33Sg+PPetLo554sn3lzfZrF/Y1v82dLcH6+" ascii
    $s20 = "vLEB/epy8SN4/e1foR9Sz1RDG4k6a5e3rVuTJVG/Ikxdt+ircp1KdlA/3/YekV8FlBc0gSltqfRtQWBXvVLCerwNT6wNQhu4kg3XuC2iEQLamgzLF+GLPSa+WJbrlFdp" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 800KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}